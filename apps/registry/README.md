# pap-registry

A standalone, hostable federated PAP agent registry. Deploy one registry node (or a mesh of them) so that PAP-compatible agents and Papillion instances can discover each other across an open network.

This is the reference implementation of the federation protocol described in the PAP specification. It is not a SaaS product or a central authority — anyone can run their own node.

## Features

- **Axum SSR backend** with Leptos 0.8 — server-side rendered web UI, no separate WASM build step for the UI pages
- **SQLite or Postgres** persistence — SQLite for single-node deployments, Postgres for clustered/HA setups
- **Admin REST API** — token-authenticated CRUD for agents and peers
- **Leptos SSR web UI** — Dashboard, Agents, Peers, and Settings pages rendered server-side
- **Federation protocol** — PAP-compatible `/federation/*` endpoints for query, announce, and peer exchange
- **Did:key node identity** — each registry generates and persists an Ed25519 keypair; DID is stable across restarts
- **TLS certificate fingerprint pinning** — outgoing peer connections use SHA-256 TOFU pinning via a custom rustls `ServerCertVerifier` (no CA dependency; DIDs are the trust root)
- **Ed25519 signature verification** — agent advertisements are verified at ingest; unsigned or tampered payloads are rejected with `422 Unprocessable Entity`
- **Paginated full-text search** — SQLite FTS5 and Postgres tsvector backends; FTS special characters are escaped before interpolation
- **Docker deployment** — multi-stage Dockerfile with a separate test-runner stage

## Quickstart

### From source

```bash
# From the repo root (pap/)
cargo run -p pap-registry --features ssr
```

The registry starts on `http://0.0.0.0:7890` by default.

### Docker

```bash
# Build from the repo root
docker build -f apps/registry/Dockerfile -t pap-registry .

# Run with a persistent volume
docker run -p 7890:7890 \
  -v registry_data:/data \
  -e PAP_REGISTRY_ADMIN_TOKEN=change-me \
  pap-registry
```

### Docker Compose

```bash
cd apps/registry
# Edit PAP_REGISTRY_ENDPOINT in docker-compose.yml to your server's hostname/IP
docker compose up -d

# Run the test suite in an isolated container
docker compose --profile test run --rm test
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PAP_REGISTRY_PORT` | `7890` | Port the HTTP server listens on |
| `PAP_REGISTRY_HOST` | `0.0.0.0` | Bind address |
| `PAP_REGISTRY_ENDPOINT` | `http://<host>:<port>` | Public URL advertised to federation peers. Set this to your server's externally reachable address. |
| `PAP_REGISTRY_DB` | `./registry.db` | Path to the SQLite database file. Ignored if `db.yml` is present. |
| `PAP_REGISTRY_ADMIN_TOKEN` | _(unset — open)_ | If set, all admin API routes (`/api/*`) require `Authorization: Bearer <token>`. Omit only on fully trusted networks. |

### Postgres (optional)

Create a `db.yml` file in the working directory to switch to Postgres:

```yaml
driver: postgres
url: "postgres://user:pass@localhost:5432/pap_registry"
```

When `db.yml` is present, `PAP_REGISTRY_DB` is ignored.

## API Endpoints

### Admin REST API (`/api/*`)

All endpoints require `Authorization: Bearer <token>` when `PAP_REGISTRY_ADMIN_TOKEN` is configured.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/status` | Registry identity, agent/peer counts, version |
| `GET` | `/api/agents` | Paginated agent list; supports `?q=<text>&page=<n>&per_page=<n>` |
| `POST` | `/api/agents` | Register an agent (`AgentAdvertisement` JSON body; Ed25519 signature required) |
| `DELETE` | `/api/agents/{hash}` | Remove an agent by content hash |
| `GET` | `/api/peers` | List known federation peers |
| `POST` | `/api/peers` | Add a peer (`{ did, endpoint, cert_fingerprint? }`) |
| `DELETE` | `/api/peers/{did}` | Remove a peer (DID must be percent-encoded) |
| `POST` | `/api/peers/{did}/sync` | Pull-sync agents from a peer on demand |

### Federation Protocol (`/federation/*`)

These endpoints implement the PAP federation protocol. No authentication required — they are the public face of the registry node.

| Method | Path | Description |
|---|---|---|
| `GET` | `/federation/identity` | Node DID and TLS certificate fingerprint |
| `GET` | `/federation/query?action=<schema.org-action>` | Query agents by action type; returns a `FederationMessage::QueryResponse` |
| `POST` | `/federation/announce` | Receive an agent advertisement from a peer |
| `GET` | `/federation/peers` | Return this node's known peer list for gossip-based discovery |

### Web UI

The web UI is served at `/` and provides:

- **Dashboard** — registry overview (agent count, peer count, node DID)
- **Agents** — searchable, paginated agent list with DID display and capability badges
- **Peers** — federation peer management
- **Settings** — node configuration

## Federation Protocol

PAP uses a push/pull mesh for agent discovery:

1. **Identity exchange** — a new peer calls `GET /federation/identity` to obtain the node DID and TLS cert fingerprint
2. **TOFU pinning** — the fingerprint is stored; all subsequent connections to that peer are verified against it using `PinnedCertVerifier` (SHA-256, constant-time comparison)
3. **Pull sync** — call `POST /api/peers/{did}/sync` (or the automatic background sync) to pull all agents from a peer via `GET /federation/query?action=*`
4. **Push announce** — agents can push their advertisement to a known peer via `POST /federation/announce`
5. **Peer gossip** — `GET /federation/peers` exposes the known peer list; clients can use it to bootstrap discovery

All agent advertisements received via federation are Ed25519-verified before being written to the database. Invalid-signature ads from a compromised peer are silently dropped.

## TLS and Security

- Each registry node generates a self-signed TLS certificate at startup. The certificate is bound to the node's stable DID.
- Peers that use self-signed certificates must supply a `cert_fingerprint` (SHA-256 hex, colon-separated or bare) when they are registered.
- Outgoing peer connections use `PinnedCertVerifier` (`apps/registry/src/tls.rs`) — a custom rustls `ServerCertVerifier` that pins by fingerprint and validates the TLS handshake signature using ring.
- Peers with CA-signed certificates can omit the fingerprint; they are validated by the system root store.
- Admin API routes use constant-time Bearer token comparison to prevent timing attacks.

## Running Tests

```bash
# Unit + integration tests (requires the ssr feature)
cargo test -p pap-registry --features ssr

# Via Docker (isolated, no local toolchain required)
docker buildx build --target test --progress=plain -f apps/registry/Dockerfile .

# Via Docker Compose
docker compose -f apps/registry/docker-compose.yml --profile test run --rm test
```

The test suite covers: SQLite CRUD layer, auth middleware (bearer token parsing, 401/200 flows), all admin route handlers via `tower::ServiceExt::oneshot()`, FTS5 SQL injection regression (I8), and Ed25519 signature verification at ingest.

## Crate Layout

```
apps/registry/
  Cargo.toml          # pap-registry crate (ssr + hydrate features)
  Dockerfile          # Multi-stage: builder, test, runtime
  docker-compose.yml  # Single-node deployment + test profile
  src/
    main.rs           # Startup: DB, identity, registry hydration, router assembly
    config.rs         # Config::from_env() — all env var bindings
    state.rs          # AppState shared across handlers
    tls.rs            # PinnedCertVerifier (rustls) + build_peer_client()
    db/
      mod.rs          # RegistryStore enum (Sqlite | Postgres)
      sqlite.rs       # SqliteStore implementation
      postgres.rs     # PostgresStore implementation
      config.rs       # DbConfig::resolve() — db.yml or env var
      migrations/     # SQLite and Postgres migration scripts
    routes/
      admin.rs        # /api/* handlers + tests
      leptos_handler.rs  # Leptos SSR integration
    ui/
      app.rs          # Leptos app root
      api.rs          # Client-side API helpers
      pages/          # Dashboard, Agents, Peers, Settings pages
      components/     # Shared UI components
```
