# Build context: repo root (pap/)
#   docker build -f apps/registry/Dockerfile -t pap-registry .

# ── Stage 1: Build server binary + WASM bundle with cargo-leptos ─────────────
FROM rust:1.94-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates pkg-config libssl-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown
RUN cargo install cargo-binstall --locked
RUN cargo binstall cargo-leptos --no-confirm

WORKDIR /build

# Workspace root
COPY Cargo.toml Cargo.lock ./
COPY vendor-icu ./vendor-icu

# All crates in pap-registry's transitive dependency graph:
#   pap-registry → pap-federation → pap-marketplace → pap-core → pap-did
#   pap-registry (ssr) → pap-agents → pap-credential-store → pap-webauthn
#                       → pap-transport → pap-proto, pap-credential
#   pap-core optionally depends on pap-tee (workspace member must be present)
COPY crates/pap-did              ./crates/pap-did
COPY crates/pap-tee              ./crates/pap-tee
COPY crates/pap-core             ./crates/pap-core
COPY crates/pap-marketplace      ./crates/pap-marketplace
COPY crates/pap-federation       ./crates/pap-federation
COPY crates/pap-credential       ./crates/pap-credential
COPY crates/pap-credential-store ./crates/pap-credential-store
COPY crates/pap-webauthn         ./crates/pap-webauthn
COPY crates/pap-proto            ./crates/pap-proto
COPY crates/pap-transport        ./crates/pap-transport
COPY crates/pap-agents           ./crates/pap-agents
# pap-test-utils is a dev-dep of pap-transport; cargo needs the crate present
# in the workspace to resolve the manifest even during a release build.
COPY crates/pap-test-utils       ./crates/pap-test-utils

# The registry app (server + UI in one crate)
COPY apps/registry/Cargo.toml ./apps/registry/Cargo.toml
COPY apps/registry/src ./apps/registry/src
# CSS source referenced by [[workspace.metadata.leptos]] style-file
COPY apps/registry/styles ./apps/registry/styles
# Static assets (icon, favicon, logo)
COPY apps/registry/assets ./apps/registry/assets

# Patch the workspace members list to remove crates we didn't copy.
# Anchor to lines starting with whitespace+quote (member entries only),
# so workspace.dependencies path entries are left intact.
RUN sed -i \
    -e '/^[[:space:]]*"crates\/pap-python"/d' \
    -e '/^[[:space:]]*"crates\/pap-c"/d' \
    -e '/^[[:space:]]*"crates\/pap-ecash"/d' \
    -e '/^[[:space:]]*"crates\/pap-wasm"/d' \
    -e '/^[[:space:]]*"crates\/pap-bluefield"/d' \
    -e '/^[[:space:]]*"crates\/pap-sandbox"/d' \
    -e '/^[[:space:]]*"crates\/pap-test-utils"/d' \
    -e '/^[[:space:]]*"crates\/papillon-shared"/d' \
    -e '/^[[:space:]]*"apps\/papillon"/d' \
    -e '/^[[:space:]]*"benches"/d' \
    -e '/^[[:space:]]*"examples\//d' \
    -e '/^pap-test-utils[[:space:]]*=/d' \
    -e '/^papillon-shared[[:space:]]*=/d' \
    Cargo.toml

# Strip pap-test-utils dev-dep from crate manifests (the crate is not copied).
RUN sed -i -e '/^pap-test-utils[[:space:]]*=/d' \
    crates/pap-core/Cargo.toml \
    crates/pap-credential/Cargo.toml \
    crates/pap-federation/Cargo.toml \
    crates/pap-transport/Cargo.toml

# Build server binary (ssr feature) + WASM bundle (hydrate feature) in one step
RUN cargo leptos build --release -p pap-registry

# ── Stage 2: Test runner ─────────────────────────────────────────────────────
# Run with: docker buildx build --target test --progress=plain -f apps/registry/Dockerfile .
# Via compose: docker compose -f apps/registry/docker-compose.yml --profile test build --progress plain test
FROM rust:1.94-slim AS test

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY vendor-icu ./vendor-icu

COPY crates/pap-did              ./crates/pap-did
COPY crates/pap-tee              ./crates/pap-tee
COPY crates/pap-core             ./crates/pap-core
COPY crates/pap-marketplace      ./crates/pap-marketplace
COPY crates/pap-federation       ./crates/pap-federation
COPY crates/pap-credential       ./crates/pap-credential
COPY crates/pap-credential-store ./crates/pap-credential-store
COPY crates/pap-webauthn         ./crates/pap-webauthn
COPY crates/pap-proto            ./crates/pap-proto
COPY crates/pap-transport        ./crates/pap-transport
COPY crates/pap-agents           ./crates/pap-agents
COPY crates/pap-test-utils       ./crates/pap-test-utils

COPY apps/registry/Cargo.toml ./apps/registry/Cargo.toml
COPY apps/registry/src        ./apps/registry/src

RUN sed -i \
    -e '/^[[:space:]]*"crates\/pap-python"/d' \
    -e '/^[[:space:]]*"crates\/pap-c"/d' \
    -e '/^[[:space:]]*"crates\/pap-ecash"/d' \
    -e '/^[[:space:]]*"crates\/pap-wasm"/d' \
    -e '/^[[:space:]]*"crates\/pap-bluefield"/d' \
    -e '/^[[:space:]]*"crates\/pap-sandbox"/d' \
    -e '/^[[:space:]]*"crates\/pap-test-utils"/d' \
    -e '/^[[:space:]]*"crates\/papillon-shared"/d' \
    -e '/^[[:space:]]*"apps\/papillon"/d' \
    -e '/^[[:space:]]*"benches"/d' \
    -e '/^[[:space:]]*"examples\//d' \
    -e '/^pap-test-utils[[:space:]]*=/d' \
    -e '/^papillon-shared[[:space:]]*=/d' \
    Cargo.toml

# Strip pap-test-utils dev-dep from crate manifests (the crate is not copied).
RUN sed -i -e '/^pap-test-utils[[:space:]]*=/d' \
    crates/pap-core/Cargo.toml \
    crates/pap-credential/Cargo.toml \
    crates/pap-federation/Cargo.toml \
    crates/pap-transport/Cargo.toml

RUN cargo test -p pap-registry --features ssr

# ── Stage 3: Minimal runtime image ───────────────────────────────────────────
FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data /app/site

WORKDIR /app

# cargo-leptos outputs server binary to target/release/
COPY --from=builder /build/target/release/pap-registry ./pap-registry
# WASM pkg + compiled CSS land in target/site/
COPY --from=builder /build/target/site ./site
# Static assets (icon, favicon, logo)
COPY --from=builder /build/apps/registry/assets ./assets

ENV PAP_REGISTRY_HOST=0.0.0.0
ENV PAP_ASSETS_DIR=/app/assets
ENV PAP_REGISTRY_PORT=7890
ENV PAP_REGISTRY_DB=/data/registry.db
ENV LEPTOS_SITE_ROOT=/app/site

VOLUME ["/data"]

EXPOSE 7890

ENTRYPOINT ["/app/pap-registry"]
