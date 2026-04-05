# Contributing to PAP

PAP is published at draft stage specifically to invite feedback, objections, and alternative proposals.

## What We Want

- **Protocol-level feedback**: Does the trust model hold? Are there attack vectors we've missed? Can the capture test be tightened?
- **Competing implementations**: A Python or TypeScript implementation would prove the protocol is language-independent. If the spec is only readable in Rust, the spec is incomplete.
- **Integration patterns**: How to add PAP compliance to an existing LangChain agent, CrewAI workflow, or MCP tool provider.
- **Formal specification review**: The protocol currently lives in code. An RFC-style document needs adversarial review.
- **Real-world testing**: Run the examples against actual services. Where does the protocol break? What's missing?

## Prerequisites

### Required

- **Rust stable toolchain** — install via [rustup](https://rustup.rs/):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **cargo** — included with rustup

### System Dependencies (Linux)

The Tauri-based desktop app and several crates require native libraries:

```bash
sudo apt-get update && sudo apt-get install -y \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  libssl-dev
```

The registry SSR tests additionally need:

```bash
sudo apt-get install -y pkg-config libpq-dev
```

### System Dependencies (macOS)

Install Xcode Command Line Tools:

```bash
xcode-select --install
```

### Optional (for specific subsystems)

| Tool | Version | Needed for |
|------|---------|------------|
| Node.js + npm | 20+ | Browser extension, E2E tests |
| Python | 3.8+ | `pap-python` bindings |
| [maturin](https://www.maturin.rs/) | 1.5+ | Building Python bindings |
| Java (JDK) | 17+ | Java bindings |
| Gradle | 8+ | Java binding tests |
| [wasm-pack](https://rustwasm.github.io/wasm-pack/) | latest | WASM builds |
| [trunk](https://trunkrs.dev/) | latest | Leptos frontend builds |
| [Playwright](https://playwright.dev/) | 1.50+ | E2E smoke tests |

## Quick Start

```bash
git clone https://github.com/Baur-Software/pap.git
cd pap
cargo build --workspace
cargo test --workspace
```

To run a protocol example:

```bash
cargo run -p search
```

## Project Structure

```
pap/
├── crates/                 # Protocol library crates
│   ├── pap-core/           #   Mandate, scope, session, receipt, extensions
│   ├── pap-did/            #   DID generation, session keypairs (did:key, Ed25519)
│   ├── pap-credential/     #   W3C VC envelope, SD-JWT selective disclosure
│   ├── pap-credential-store/ # Encrypted vault for seeds, VCs, continuity tokens
│   ├── pap-proto/          #   Protocol message types and envelope
│   ├── pap-transport/      #   HTTP client/server for 6-phase handshake
│   ├── pap-federation/     #   Cross-registry sync, announce, peer exchange
│   ├── pap-marketplace/    #   Agent advertisement, registry, discovery
│   ├── pap-agents/         #   Shared agent implementations (AgentExecutor trait)
│   ├── pap-webauthn/       #   WebAuthn signer abstraction + software fallback
│   ├── pap-tee/            #   Trusted execution environment support
│   ├── pap-c/              #   C FFI bindings (cdylib + staticlib)
│   ├── pap-wasm/           #   WebAssembly bindings (@pap/sdk npm package)
│   ├── pap-python/         #   PyO3 bindings for Python
│   └── papillon-shared/    #   Shared models between Papillon frontend/backend
├── apps/
│   ├── papillon/           # Tauri desktop reference implementation
│   ├── papillon-extension/ # Chrome MV3 browser extension
│   └── registry/           # Chrysalis federated registry (Axum + Leptos SSR)
├── bindings/
│   ├── cpp/                # C++ RAII header-only wrapper
│   ├── csharp/             # .NET 8 P/Invoke bindings
│   └── java/               # JNA-based Java bindings
├── examples/               # 10 self-contained protocol examples
├── benches/                # Criterion.rs benchmarks + regression gate
├── docs/                   # Specification and protocol documentation
├── e2e/                    # Playwright E2E tests
└── ci/                     # CI helper scripts
```

## How to Contribute

### Issues

File an issue for:
- Protocol design questions or concerns
- Implementation bugs
- Missing test coverage
- Documentation gaps
- Feature requests (evaluated against the capture test)

### Pull Requests

1. Fork the repo
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure `cargo test --workspace` passes
5. Ensure `cargo clippy --workspace` has no warnings
6. Ensure `cargo fmt --all` is clean
7. Open a PR with a clear description of what changed and why

### Branch Naming

Use conventional prefixes:

- `feat/short-description` — new features
- `fix/short-description` — bug fixes
- `chore/short-description` — maintenance, deps, CI
- `docs/short-description` — documentation changes

### Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/). Format:

```
<type>(<optional scope>): <description>
```

Types: `feat`, `fix`, `chore`, `style`, `docs`, `refactor`, `test`, `perf`

Examples from recent history:
```
feat: Chrysalis federation integration
fix: resolve all pre-existing WASM Clippy warnings surfaced by cache bust
style: apply rustfmt to pap_uri module
chore: bump version to 0.6.0, update CHANGELOG for pap:// URI scheme
feat(generic): render PapLink as confirmation-gated intent button
```

### The Capture Test

Every contribution is evaluated against a single question: **does this reduce or expand the attack surface for incumbent platform capture?**

Proposals that introduce new trusted third parties, centralize discovery, soften disclosure enforcement, or create compatibility with metering models should be evaluated as potential capture vectors first and protocol improvements second.

This is not a purity test. It is a design constraint. The protocol's value is that it structurally prevents the patterns that captured every previous generation of open standards.

## Running Tests

### Rust Workspace Tests

```bash
# All tests
cargo test --workspace

# Single crate
cargo test -p pap-core

# Registry with SSR features
cargo test -p pap-registry --features ssr
```

### Benchmarks

```bash
# Run benchmarks
cargo bench -p pap-bench

# Check for regressions (>20% p50 threshold)
bash benches/check_regression.sh
```

Performance targets (p50):
- Ed25519 keypair: < 1 ms
- DID derivation: < 0.5 ms
- Mandate sign: < 2 ms
- Chain verify (depth 3): < 5 ms
- SD-JWT issue: < 3 ms
- Session open: < 20 ms

### Python Bindings

```bash
cd crates/pap-python
maturin develop
pytest
```

### Java Bindings

Build the C FFI library first, then run Gradle tests:

```bash
cargo build -p pap-c --release
cd bindings/java
./gradlew test
```

### E2E Smoke Tests (Papillon Desktop)

```bash
cd e2e
npm install
npx playwright install chromium --with-deps
cd ../apps/papillon/frontend && trunk build --release && cd ../../../e2e
npx playwright test tests/smoke.spec.ts --workers=1
```

## Running Examples

Each example demonstrates a specific protocol feature. Run them with `cargo run -p <name>`:

```bash
cargo run -p search                # End-to-end agent search
cargo run -p travel-booking        # Multi-step travel booking workflow
cargo run -p delegation-chain      # Mandate delegation chain
cargo run -p payment               # Payment handling
cargo run -p networked-search      # Networked agent search
cargo run -p webauthn-ceremony     # WebAuthn authentication ceremony
cargo run -p federated-discovery   # Federated registry discovery
cargo run -p credential-lifecycle  # Credential lifecycle management
cargo run -p protocol-envelope     # Protocol message envelope
cargo run -p tee-attestation       # Trusted execution environment attestation
```

## Building the Browser Extension

The Papillon browser extension requires WASM bindings from `pap-wasm`:

```bash
cd apps/papillon-extension
npm install
npm run build:wasm    # builds pap-wasm → wasm/ directory
npm run build         # TypeScript check + Vite build → dist/

# For development (watch mode):
npm run dev
```

For Firefox, generate the Firefox-compatible manifest:

```bash
npm run firefox:manifest
```

## CI Pipeline

All checks run on every push to `main` and on pull requests. Your PR must pass all of them.

| Job | What it does | Reproduce locally |
|-----|-------------|-------------------|
| **Check** | `cargo check --workspace --all-targets` | Same command |
| **Test** | `cargo test --workspace` | Same command |
| **Test (registry SSR)** | `cargo test -p pap-registry --features ssr` | Same command |
| **Clippy** | `cargo clippy --workspace --all-targets -- -D warnings` | Same command |
| **Format** | `cargo fmt --all -- --check` | `cargo fmt --all` to fix |
| **Docker workspace** | Validates Dockerfile workspace consistency | `bash ci/check-docker-workspace.sh` |
| **Benchmark** | Runs benchmarks + regression gate (>20% p50) | `cargo bench -p pap-bench && bash benches/check_regression.sh` |
| **Smoke test** | Playwright E2E tests for Papillon desktop | See [E2E Smoke Tests](#e2e-smoke-tests-papillon-desktop) |
| **Chrysalis E2E** | Integration tests for Chrysalis registry (Docker) | See [E2E Smoke Tests](#e2e-smoke-tests-papillon-desktop) |

Before opening a PR, run at minimum:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Code Style

- Rust stable toolchain
- `cargo fmt` for formatting (config: `rustfmt.toml` with `edition = "2021"`)
- `cargo clippy` with `-D warnings` — all warnings are treated as errors in CI
- Tests co-located with implementation (in `mod tests` blocks)
- All public types documented with `///` doc comments
- Examples should be self-contained and demonstrate a specific protocol feature

## Architecture Decisions

Major architectural changes should be discussed in an issue before implementation. This includes:
- New crates
- Changes to the mandate/session/receipt types
- New protocol phases or extensions
- Transport layer changes
- Federation protocol changes

## License

By contributing, you agree that your contributions will be licensed under the project's MIT OR Apache-2.0 dual license.
