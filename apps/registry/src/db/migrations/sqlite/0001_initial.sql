-- Node identity: singleton (id always = 1)
-- Stores the Ed25519 signing key so the node DID is stable across restarts.
CREATE TABLE IF NOT EXISTS node_identity (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    did         TEXT NOT NULL,
    signing_key BLOB NOT NULL   -- 32-byte Ed25519 seed
);

-- Agent advertisements
CREATE TABLE IF NOT EXISTS agents (
    hash            TEXT PRIMARY KEY,
    ad_json         TEXT NOT NULL,              -- full AgentAdvertisement as JSON
    name            TEXT NOT NULL DEFAULT '',
    provider_name   TEXT NOT NULL DEFAULT '',
    capability_json TEXT NOT NULL DEFAULT '[]', -- JSON array, e.g. ["schema:SearchAction"]
    inserted_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- FTS5 virtual table for fast full-text search across name, provider, capabilities.
-- Only used by the SQLite backend; Postgres uses tsvector added at runtime.
CREATE VIRTUAL TABLE IF NOT EXISTS agents_fts USING fts5(
    hash UNINDEXED,
    name,
    provider_name,
    capability_text,
    content='agents',
    content_rowid='rowid'
);

-- Keep FTS in sync on insert
CREATE TRIGGER IF NOT EXISTS agents_ai AFTER INSERT ON agents BEGIN
    INSERT INTO agents_fts(rowid, hash, name, provider_name, capability_text)
    VALUES (
        new.rowid,
        new.hash,
        new.name,
        new.provider_name,
        replace(replace(replace(new.capability_json, '[', ''), ']', ''), '"', '')
    );
END;

-- Keep FTS in sync on delete
CREATE TRIGGER IF NOT EXISTS agents_ad AFTER DELETE ON agents BEGIN
    INSERT INTO agents_fts(agents_fts, rowid, hash, name, provider_name, capability_text)
    VALUES (
        'delete',
        old.rowid,
        old.hash,
        old.name,
        old.provider_name,
        replace(replace(replace(old.capability_json, '[', ''), ']', ''), '"', '')
    );
END;

-- Federation peers
CREATE TABLE IF NOT EXISTS peers (
    did              TEXT PRIMARY KEY,
    endpoint         TEXT NOT NULL,
    cert_fingerprint TEXT,
    last_sync        TEXT    -- ISO-8601 UTC datetime, or NULL if never synced
);
