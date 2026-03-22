# Build context: repo root (pap/)
#   docker build -f apps/registry/Dockerfile -t pap-registry .
#
# ── Stage 1: Build the Leptos WASM frontend ─────────────────────────────────
FROM rust:1.82-slim AS frontend-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown
RUN cargo install trunk --locked

WORKDIR /build/frontend
COPY apps/registry/frontend/Cargo.toml apps/registry/frontend/Cargo.lock* ./
COPY apps/registry/frontend/src ./src
COPY apps/registry/frontend/styles ./styles
COPY apps/registry/frontend/index.html ./

RUN trunk build --release

# ── Stage 2: Build the Axum backend ─────────────────────────────────────────
FROM rust:1.82-slim AS backend-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Workspace root
COPY Cargo.toml Cargo.lock ./
COPY vendor-icu ./vendor-icu

# Only the crates pap-registry actually depends on
COPY crates/pap-did ./crates/pap-did
COPY crates/pap-marketplace ./crates/pap-marketplace
COPY crates/pap-federation ./crates/pap-federation

# Stub out workspace members we don't need so Cargo can parse the workspace.
# These are not compiled — Cargo only reads their Cargo.toml for resolution.
RUN mkdir -p apps/papillion crates/pap-core crates/pap-credential \
    crates/pap-transport crates/pap-proto crates/pap-webauthn \
    crates/pap-python crates/papillion-shared

COPY crates/pap-core/Cargo.toml ./crates/pap-core/Cargo.toml
COPY crates/pap-credential/Cargo.toml ./crates/pap-credential/Cargo.toml
COPY crates/pap-transport/Cargo.toml ./crates/pap-transport/Cargo.toml
COPY crates/pap-proto/Cargo.toml ./crates/pap-proto/Cargo.toml
COPY crates/pap-webauthn/Cargo.toml ./crates/pap-webauthn/Cargo.toml
COPY crates/pap-python/Cargo.toml ./crates/pap-python/Cargo.toml
COPY crates/papillion-shared/Cargo.toml ./crates/papillion-shared/Cargo.toml
COPY apps/papillion/Cargo.toml ./apps/papillion/Cargo.toml

# The registry app
COPY apps/registry/Cargo.toml ./apps/registry/Cargo.toml
COPY apps/registry/src ./apps/registry/src

# Build only pap-registry (other workspace members are not compiled)
RUN cargo build --release -p pap-registry

# ── Stage 3: Minimal runtime image ──────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=backend-builder /build/target/release/pap-registry ./pap-registry
COPY --from=frontend-builder /build/frontend/dist ./dist

ENV PAP_REGISTRY_HOST=0.0.0.0
ENV PAP_REGISTRY_PORT=7890
ENV PAP_REGISTRY_DIST=/app/dist

EXPOSE 7890

ENTRYPOINT ["/app/pap-registry"]
