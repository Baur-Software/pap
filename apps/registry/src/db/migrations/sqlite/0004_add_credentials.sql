-- Principal credential vault: secrets, tokens, VCs, and attestations.
-- SECURITY NOTE: payload stores ciphertext. Encrypt secrets at the application layer
-- (e.g., with a key derived from a master secret) before insertion. Never log or
-- serialize the plaintext payload directly.
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

-- Ensure updated_at refreshes on every row modification.
CREATE TRIGGER IF NOT EXISTS trg_credentials_updated_at
AFTER UPDATE ON credentials
FOR EACH ROW
BEGIN
    UPDATE credentials SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = OLD.id;
END;
