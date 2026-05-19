use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use pap_federation::peer::RegistryPeer;
use pap_marketplace::AgentAdvertisement;

use super::{AgentEntry, AgentsPage, CredentialEntry, CredentialsPage, NodeIdentity};

pub struct PostgresStore {
    pub pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPool::connect(url)
            .await
            .with_context(|| format!("Failed to connect to Postgres at {url}"))?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        // Run the Postgres-specific migration (no FTS5 virtual table or SQLite triggers).
        // Full-text search is added below via the generated tsvector column.
        sqlx::migrate!("src/db/migrations/postgres")
            .run(&self.pool)
            .await
            .context("Postgres migration failed")?;

        // Add Postgres-specific full-text search (idempotent).
        sqlx::query(
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS search_vec tsvector
             GENERATED ALWAYS AS (
                 to_tsvector('english',
                     coalesce(name, '') || ' ' ||
                     coalesce(provider_name, '') || ' ' ||
                     coalesce(capability_json, ''))
             ) STORED",
        )
        .execute(&self.pool)
        .await
        .ok(); // ignore "column already exists"

        sqlx::query("CREATE INDEX IF NOT EXISTS agents_search_gin ON agents USING GIN(search_vec)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // ── Node identity ────────────────────────────────────────────────────────

    pub async fn load_identity(&self) -> Result<Option<NodeIdentity>> {
        let row = sqlx::query_as::<_, (String, Vec<u8>)>(
            "SELECT did, signing_key FROM node_identity WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|(did, key_bytes)| {
            if key_bytes.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&key_bytes);
                Some(NodeIdentity {
                    did,
                    signing_key_bytes: bytes,
                })
            } else {
                None
            }
        }))
    }

    pub async fn save_identity(&self, identity: &NodeIdentity) -> Result<()> {
        sqlx::query(
            "INSERT INTO node_identity (id, did, signing_key) VALUES (1, $1, $2)
             ON CONFLICT(id) DO UPDATE SET did = EXCLUDED.did, signing_key = EXCLUDED.signing_key",
        )
        .bind(&identity.did)
        .bind(identity.signing_key_bytes.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Agents ───────────────────────────────────────────────────────────────

    pub async fn load_all_agents(&self) -> Result<Vec<AgentAdvertisement>> {
        let rows =
            sqlx::query_as::<_, (String,)>("SELECT ad_json FROM agents ORDER BY inserted_at ASC")
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter()
            .map(|(json,)| {
                serde_json::from_str(&json).context("Failed to deserialize agent from DB")
            })
            .collect()
    }

    pub async fn insert_agent(&self, hash: &str, ad: &AgentAdvertisement) -> Result<()> {
        let ad_json = serde_json::to_string(ad)?;
        let cap_json = serde_json::to_string(&ad.capability)?;
        sqlx::query(
            "INSERT INTO agents (hash, ad_json, name, provider_name, capability_json, version)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT(hash) DO NOTHING",
        )
        .bind(hash)
        .bind(&ad_json)
        .bind(&ad.name)
        .bind(&ad.provider.name)
        .bind(&cap_json)
        .bind(&ad.version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_agent(&self, hash: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM agents WHERE hash = $1")
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count_agents_by_principal(&self, provider_did: &str) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agents WHERE (ad_json::json)->>'provider'->>'did' = $1",
        )
        .bind(provider_did)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    pub async fn search_agents(
        &self,
        q: Option<&str>,
        version: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> Result<AgentsPage> {
        let offset = page.saturating_sub(1) * per_page;

        let (total, rows): (u64, Vec<(String, String)>) = if let Some(query) =
            q.filter(|s| !s.is_empty())
        {
            if let Some(ver) = version {
                let total: i64 = sqlx::query_as::<_, (i64,)>(
                    "SELECT COUNT(*) FROM agents
                         WHERE search_vec @@ plainto_tsquery('english', $1) AND version = $2",
                )
                .bind(query)
                .bind(ver)
                .fetch_one(&self.pool)
                .await
                .map(|(n,)| n)
                .unwrap_or(0);

                let rows = sqlx::query_as::<_, (String, String)>(
                    "SELECT hash, ad_json FROM agents
                         WHERE search_vec @@ plainto_tsquery('english', $1) AND version = $2
                         ORDER BY ts_rank(search_vec, plainto_tsquery('english', $1)) DESC
                         LIMIT $3 OFFSET $4",
                )
                .bind(query)
                .bind(ver)
                .bind(per_page as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await?;

                (total as u64, rows)
            } else {
                let total: i64 = sqlx::query_as::<_, (i64,)>(
                        "SELECT COUNT(*) FROM agents WHERE search_vec @@ plainto_tsquery('english', $1)",
                    )
                    .bind(query)
                    .fetch_one(&self.pool)
                    .await
                    .map(|(n,)| n)
                    .unwrap_or(0);

                let rows = sqlx::query_as::<_, (String, String)>(
                    "SELECT hash, ad_json FROM agents
                         WHERE search_vec @@ plainto_tsquery('english', $1)
                         ORDER BY ts_rank(search_vec, plainto_tsquery('english', $1)) DESC
                         LIMIT $2 OFFSET $3",
                )
                .bind(query)
                .bind(per_page as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await?;

                (total as u64, rows)
            }
        } else if let Some(ver) = version {
            let total: i64 =
                sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM agents WHERE version = $1")
                    .bind(ver)
                    .fetch_one(&self.pool)
                    .await
                    .map(|(n,)| n)
                    .unwrap_or(0);

            let rows = sqlx::query_as::<_, (String, String)>(
                    "SELECT hash, ad_json FROM agents WHERE version = $1 ORDER BY inserted_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(ver)
                .bind(per_page as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await?;

            (total as u64, rows)
        } else {
            let total: i64 = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM agents")
                .fetch_one(&self.pool)
                .await
                .map(|(n,)| n)
                .unwrap_or(0);

            let rows = sqlx::query_as::<_, (String, String)>(
                "SELECT hash, ad_json FROM agents ORDER BY inserted_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(per_page as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?;

            (total as u64, rows)
        };

        let items = rows
            .into_iter()
            .map(|(hash, json)| {
                let ad: AgentAdvertisement =
                    serde_json::from_str(&json).context("Failed to deserialize agent")?;
                Ok(AgentEntry { hash, ad })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(AgentsPage {
            items,
            total,
            page,
            per_page,
        })
    }

    // ── Peers ────────────────────────────────────────────────────────────────

    pub async fn load_all_peers(&self) -> Result<Vec<RegistryPeer>> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
            "SELECT did, endpoint, cert_fingerprint, last_sync FROM peers",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(did, endpoint, cert_fingerprint, last_sync)| {
                let last_sync = last_sync
                    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc));
                RegistryPeer {
                    did,
                    endpoint,
                    cert_fingerprint,
                    last_sync,
                    trust_signals: None,
                    status: pap_federation::PeerStatus::Active,
                    registered_at: None,
                }
            })
            .collect())
    }

    pub async fn upsert_peer(&self, peer: &RegistryPeer) -> Result<()> {
        let last_sync = peer.last_sync.map(|t| t.to_rfc3339());
        sqlx::query(
            "INSERT INTO peers (did, endpoint, cert_fingerprint, last_sync)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(did) DO UPDATE SET
                 endpoint = EXCLUDED.endpoint,
                 cert_fingerprint = EXCLUDED.cert_fingerprint,
                 last_sync = EXCLUDED.last_sync",
        )
        .bind(&peer.did)
        .bind(&peer.endpoint)
        .bind(&peer.cert_fingerprint)
        .bind(last_sync)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_peer(&self, did: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM peers WHERE did = $1")
            .bind(did)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_peer_sync_time(&self, did: &str, ts: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE peers SET last_sync = $1 WHERE did = $2")
            .bind(ts.to_rfc3339())
            .bind(did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Settings ─────────────────────────────────────────────────────────────

    pub async fn load_setting(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query_as::<_, (String,)>("SELECT value FROM settings WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(v,)| v))
    }

    pub async fn save_setting(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at)
             VALUES ($1, $2, NOW())
             ON CONFLICT(key) DO UPDATE SET
                 value = EXCLUDED.value,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Credentials ────────────────────────────────────────────────────────────

    pub async fn list_credentials(
        &self,
        q: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> Result<CredentialsPage> {
        let offset = page.saturating_sub(1) * per_page;

        let (total, rows): (
            u64,
            Vec<(
                i64,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                String,
                Option<String>,
            )>,
        ) = if let Some(query) = q.filter(|s| !s.is_empty()) {
            let pattern = format!("%{query}%");
            let total: i64 =
                sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM credentials WHERE name LIKE $1")
                    .bind(&pattern)
                    .fetch_one(&self.pool)
                    .await
                    .map(|(n,)| n)
                    .unwrap_or(0);

            let rows = sqlx::query_as::<_, (i64, String, String, String, Option<String>, Option<String>, String, String, Option<String>)>(
                "SELECT id, name, kind, payload, schema_type, issuer_did, created_at, updated_at, expires_at
                 FROM credentials WHERE name LIKE $1
                 ORDER BY updated_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(&pattern)
            .bind(per_page as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?;

            (total as u64, rows)
        } else {
            let total: i64 = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM credentials")
                .fetch_one(&self.pool)
                .await
                .map(|(n,)| n)
                .unwrap_or(0);

            let rows = sqlx::query_as::<_, (i64, String, String, String, Option<String>, Option<String>, String, String, Option<String>)>(
                "SELECT id, name, kind, payload, schema_type, issuer_did, created_at, updated_at, expires_at
                 FROM credentials
                 ORDER BY updated_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(per_page as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?;

            (total as u64, rows)
        };

        let items = rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    kind,
                    payload,
                    schema_type,
                    issuer_did,
                    created_at,
                    updated_at,
                    expires_at,
                )| {
                    CredentialEntry {
                        id,
                        name,
                        kind,
                        payload,
                        schema_type,
                        issuer_did,
                        created_at,
                        updated_at,
                        expires_at,
                    }
                },
            )
            .collect();

        Ok(CredentialsPage {
            items,
            total,
            page,
            per_page,
        })
    }

    pub async fn insert_credential(&self, entry: &CredentialEntry) -> Result<i64> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO credentials (name, kind, payload, schema_type, issuer_did, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id",
        )
        .bind(&entry.name)
        .bind(&entry.kind)
        .bind(&entry.payload)
        .bind(&entry.schema_type)
        .bind(&entry.issuer_did)
        .bind(&entry.expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn update_credential(&self, entry: &CredentialEntry) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE credentials SET
                 name = $1, kind = $2, payload = $3, schema_type = $4, issuer_did = $5, expires_at = $6
             WHERE id = $7",
        )
        .bind(&entry.name)
        .bind(&entry.kind)
        .bind(&entry.payload)
        .bind(&entry.schema_type)
        .bind(&entry.issuer_did)
        .bind(&entry.expires_at)
        .bind(entry.id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_credential(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM credentials WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}
