-- Principal credential vault: secrets, tokens, VCs, and attestations.
CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'api_token',
    payload     TEXT NOT NULL DEFAULT '{}',
    schema_type TEXT,
    issuer_did  TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_credentials_name ON credentials(name);
