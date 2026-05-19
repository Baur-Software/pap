-- Principal credential vault: secrets, tokens, VCs, and attestations.
CREATE TABLE IF NOT EXISTS credentials (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'api_token',
    payload     TEXT NOT NULL DEFAULT '{}',
    schema_type TEXT,
    issuer_did  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_credentials_name ON credentials(name);
