-- Node identity: singleton (id always = 1)
-- Stores the Ed25519 signing key so the node DID is stable across restarts.
CREATE TABLE IF NOT EXISTS node_identity (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    did         TEXT NOT NULL,
    signing_key BYTEA NOT NULL  -- 32-byte Ed25519 seed (Postgres: BYTEA, not BLOB)
);

-- Agent advertisements
CREATE TABLE IF NOT EXISTS agents (
    hash            TEXT PRIMARY KEY,
    ad_json         TEXT NOT NULL,               -- full AgentAdvertisement as JSON
    name            TEXT NOT NULL DEFAULT '',
    provider_name   TEXT NOT NULL DEFAULT '',
    capability_json TEXT NOT NULL DEFAULT '[]',  -- JSON array, e.g. ["schema:SearchAction"]
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Federation peers
CREATE TABLE IF NOT EXISTS peers (
    did              TEXT PRIMARY KEY,
    endpoint         TEXT NOT NULL,
    cert_fingerprint TEXT,
    last_sync        TEXT    -- ISO-8601 UTC datetime string, or NULL if never synced
);
