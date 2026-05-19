-- Principal credential vault: secrets, tokens, VCs, and attestations.
-- SECURITY NOTE: payload stores ciphertext. Encrypt secrets at the application layer
-- (e.g., with a key derived from a master secret) before insertion. Never log or
-- serialize the plaintext payload directly.
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

-- Ensure updated_at refreshes on every row modification.
CREATE OR REPLACE FUNCTION refresh_credentials_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_credentials_updated_at ON credentials;
CREATE TRIGGER trg_credentials_updated_at
    BEFORE UPDATE ON credentials
    FOR EACH ROW
    EXECUTE FUNCTION refresh_credentials_updated_at();
