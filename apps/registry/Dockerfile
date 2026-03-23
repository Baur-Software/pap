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
COPY crates/pap-did ./crates/pap-did
COPY crates/pap-core ./crates/pap-core
COPY crates/pap-marketplace ./crates/pap-marketplace
COPY crates/pap-federation ./crates/pap-federation

# The registry app (server + UI in one crate)
COPY apps/registry/Cargo.toml ./apps/registry/Cargo.toml
COPY apps/registry/src ./apps/registry/src
# CSS source referenced by [[workspace.metadata.leptos]] style-file
COPY apps/registry/frontend/styles ./apps/registry/frontend/styles

# Patch the workspace members list to remove crates we didn't copy.
# Anchor to lines starting with whitespace+quote (member entries only),
# so workspace.dependencies path entries are left intact.
RUN sed -i \
    -e '/^[[:space:]]*"crates\/pap-credential"/d' \
    -e '/^[[:space:]]*"crates\/pap-webauthn"/d' \
    -e '/^[[:space:]]*"crates\/pap-proto"/d' \
    -e '/^[[:space:]]*"crates\/pap-transport"/d' \
    -e '/^[[:space:]]*"crates\/pap-python"/d' \
    -e '/^[[:space:]]*"crates\/papillion-shared"/d' \
    -e '/^[[:space:]]*"apps\/papillion"/d' \
    Cargo.toml

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

COPY crates/pap-did         ./crates/pap-did
COPY crates/pap-core        ./crates/pap-core
COPY crates/pap-marketplace ./crates/pap-marketplace
COPY crates/pap-federation  ./crates/pap-federation

COPY apps/registry/Cargo.toml ./apps/registry/Cargo.toml
COPY apps/registry/src        ./apps/registry/src

RUN sed -i \
    -e '/^[[:space:]]*"crates\/pap-credential"/d' \
    -e '/^[[:space:]]*"crates\/pap-webauthn"/d'   \
    -e '/^[[:space:]]*"crates\/pap-proto"/d'       \
    -e '/^[[:space:]]*"crates\/pap-transport"/d'   \
    -e '/^[[:space:]]*"crates\/pap-python"/d'      \
    -e '/^[[:space:]]*"crates\/papillion-shared"/d' \
    -e '/^[[:space:]]*"apps\/papillion"/d'         \
    Cargo.toml

RUN cargo test -p pap-registry --features ssr

# ── Stage 3: Minimal runtime image ───────────────────────────────────────────
FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data /app/site

WORKDIR /app

# cargo-leptos outputs server binary to target/server/release/
COPY --from=builder /build/target/server/release/pap-registry ./pap-registry
# WASM pkg + compiled CSS land in target/site/
COPY --from=builder /build/target/site ./site

ENV PAP_REGISTRY_HOST=0.0.0.0
ENV PAP_REGISTRY_PORT=7890
ENV PAP_REGISTRY_DB=/data/registry.db
ENV LEPTOS_SITE_ROOT=/app/site

VOLUME ["/data"]

EXPOSE 7890

ENTRYPOINT ["/app/pap-registry"]
