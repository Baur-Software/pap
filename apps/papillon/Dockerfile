# Build context: repo root (pap/)
#   docker build -f apps/papillon/Dockerfile -t papillon .

# ── Stage 1: Build WASM frontend with trunk ───────────────────────────────────
FROM rust:1.94-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown
RUN cargo install cargo-binstall --locked
RUN cargo binstall trunk --no-confirm

WORKDIR /build

# Workspace root
COPY Cargo.toml Cargo.lock ./
COPY vendor-icu ./vendor-icu

# Crates required by papillon-ui frontend:
#   papillon-shared, pap-did, pap-core, pap-proto
#   pap-core depends on pap-credential, pap-marketplace
COPY crates/pap-did ./crates/pap-did
COPY crates/pap-core ./crates/pap-core
COPY crates/pap-credential ./crates/pap-credential
COPY crates/pap-marketplace ./crates/pap-marketplace
COPY crates/pap-proto ./crates/pap-proto
COPY crates/papillon-shared ./crates/papillon-shared

# Frontend source
COPY apps/papillon/frontend ./apps/papillon/frontend

# Patch workspace members to exclude crates we didn't copy.
# Path deps still resolve; only the member list is trimmed.
RUN sed -i \
    -e '/^[[:space:]]*"crates\/pap-credential-store"/d' \
    -e '/^[[:space:]]*"crates\/pap-agents"/d' \
    -e '/^[[:space:]]*"crates\/pap-webauthn"/d' \
    -e '/^[[:space:]]*"crates\/pap-transport"/d' \
    -e '/^[[:space:]]*"crates\/pap-federation"/d' \
    -e '/^[[:space:]]*"crates\/pap-tee"/d' \
    -e '/^[[:space:]]*"crates\/pap-python"/d' \
    -e '/^[[:space:]]*"crates\/pap-c"/d' \
    -e '/^[[:space:]]*"crates\/pap-wasm"/d' \
    -e '/^[[:space:]]*"apps\/papillon"/d' \
    -e '/^[[:space:]]*"apps\/registry"/d' \
    -e '/^[[:space:]]*"benches"/d' \
    -e '/^[[:space:]]*"examples\//d' \
    Cargo.toml

WORKDIR /build/apps/papillon/frontend
RUN trunk build --release

# ── Stage 2: Serve with nginx ─────────────────────────────────────────────────
FROM nginx:alpine AS runtime

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# SPA-friendly nginx config with COOP/COEP headers for WASM
COPY --from=builder /build/apps/papillon/frontend/dist/ /usr/share/nginx/html/

RUN cat > /etc/nginx/conf.d/papillon.conf <<'EOF'
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    # Enable SharedArrayBuffer for WASM threads
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;

    # WASM MIME type
    types {
        application/wasm wasm;
    }

    # Aggressive caching for hashed assets
    location ~* \.(wasm|js|css|woff2|png|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Embedder-Policy "require-corp" always;
    }

    # SPA fallback — serve index.html for all non-file routes
    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
