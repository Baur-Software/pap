# Build context: repo root (pap/)
#   docker build -f apps/registry/Dockerfile -t pap-registry .
#
# ── Stage 1: Build the Leptos WASM frontend ─────────────────────────────────
FROM rust:1.94-slim AS frontend-builder

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
FROM rust:1.94-slim AS backend-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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

# The registry app
COPY apps/registry/Cargo.toml ./apps/registry/Cargo.toml
COPY apps/registry/src ./apps/registry/src

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

# Build only pap-registry
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
