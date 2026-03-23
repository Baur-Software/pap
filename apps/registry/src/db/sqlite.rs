use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

use pap_federation::peer::RegistryPeer;
use pap_marketplace::AgentAdvertisement;

use super::{AgentEntry, AgentsPage, NodeIdentity};

pub struct SqliteStore {
    pub pool: SqlitePool,
}

impl SqliteStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(url)
            .await
            .with_context(|| format!("Failed to open SQLite database at {url}"))?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("src/db/migrations")
            .run(&self.pool)
            .await
            .context("SQLite migration failed")?;
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
                Some(NodeIdentity { did, signing_key_bytes: bytes })
            } else {
                None
            }
        }))
    }

    pub async fn save_identity(&self, identity: &NodeIdentity) -> Result<()> {
        sqlx::query(
            "INSERT INTO node_identity (id, did, signing_key) VALUES (1, ?, ?)
             ON CONFLICT(id) DO UPDATE SET did = excluded.did, signing_key = excluded.signing_key",
        )
        .bind(&identity.did)
        .bind(identity.signing_key_bytes.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Agents ───────────────────────────────────────────────────────────────

    pub async fn load_all_agents(&self) -> Result<Vec<AgentAdvertisement>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT ad_json FROM agents ORDER BY inserted_at ASC",
        )
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
            "INSERT OR IGNORE INTO agents (hash, ad_json, name, provider_name, capability_json)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(hash)
        .bind(&ad_json)
        .bind(&ad.name)
        .bind(&ad.provider.name)
        .bind(&cap_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_agent(&self, hash: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM agents WHERE hash = ?")
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn search_agents(
        &self,
        q: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> Result<AgentsPage> {
        let offset = page.saturating_sub(1) * per_page;

        let (total, rows): (u64, Vec<(String, String)>) =
            if let Some(query) = q.filter(|s| !s.is_empty()) {
                let total: i64 = sqlx::query_as::<_, (i64,)>(
                    "SELECT COUNT(*) FROM agents_fts WHERE agents_fts MATCH ?",
                )
                .bind(query)
                .fetch_one(&self.pool)
                .await
                .map(|(n,)| n)
                .unwrap_or(0);

                let rows = sqlx::query_as::<_, (String, String)>(
                    "SELECT a.hash, a.ad_json
                     FROM agents_fts
                     JOIN agents a ON agents_fts.rowid = a.rowid
                     WHERE agents_fts MATCH ?
                     ORDER BY rank
                     LIMIT ? OFFSET ?",
                )
                .bind(query)
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
                    "SELECT hash, ad_json FROM agents ORDER BY inserted_at DESC LIMIT ? OFFSET ?",
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

        Ok(AgentsPage { items, total, page, per_page })
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
                RegistryPeer { did, endpoint, cert_fingerprint, last_sync }
            })
            .collect())
    }

    pub async fn upsert_peer(&self, peer: &RegistryPeer) -> Result<()> {
        let last_sync = peer.last_sync.map(|t| t.to_rfc3339());
        sqlx::query(
            "INSERT INTO peers (did, endpoint, cert_fingerprint, last_sync)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(did) DO UPDATE SET
                 endpoint = excluded.endpoint,
                 cert_fingerprint = excluded.cert_fingerprint,
                 last_sync = excluded.last_sync",
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
        let result = sqlx::query("DELETE FROM peers WHERE did = ?")
            .bind(did)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_peer_sync_time(&self, did: &str, ts: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE peers SET last_sync = ? WHERE did = ?")
            .bind(ts.to_rfc3339())
            .bind(did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
