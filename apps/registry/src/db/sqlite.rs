use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

use pap_federation::peer::RegistryPeer;
use pap_marketplace::AgentAdvertisement;

use super::{AgentEntry, AgentsPage, CredentialEntry, CredentialsPage, NodeIdentity};

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
        sqlx::migrate!("src/db/migrations/sqlite")
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
            "INSERT OR IGNORE INTO agents (hash, ad_json, name, provider_name, capability_json, version)
             VALUES (?, ?, ?, ?, ?, ?)",
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
        let result = sqlx::query("DELETE FROM agents WHERE hash = ?")
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count_agents_by_principal(&self, provider_did: &str) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agents WHERE json_extract(ad_json, '$.provider.did') = ?",
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
            // Wrap user input in FTS5 phrase quotes so special characters (", (, NOT, *)
            // are treated as literals rather than FTS5 syntax operators.
            let fts_query = format!("\"{}\"", query.replace('"', "\"\""));

            if let Some(ver) = version {
                let total: i64 = sqlx::query_as::<_, (i64,)>(
                    "SELECT COUNT(*)
                         FROM agents_fts
                         JOIN agents a ON agents_fts.rowid = a.rowid
                         WHERE agents_fts MATCH ? AND a.version = ?",
                )
                .bind(&fts_query)
                .bind(ver)
                .fetch_one(&self.pool)
                .await
                .map(|(n,)| n)
                .unwrap_or(0);

                let rows = sqlx::query_as::<_, (String, String)>(
                    "SELECT a.hash, a.ad_json
                         FROM agents_fts
                         JOIN agents a ON agents_fts.rowid = a.rowid
                         WHERE agents_fts MATCH ? AND a.version = ?
                         ORDER BY rank
                         LIMIT ? OFFSET ?",
                )
                .bind(&fts_query)
                .bind(ver)
                .bind(per_page as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await?;

                (total as u64, rows)
            } else {
                let total: i64 = sqlx::query_as::<_, (i64,)>(
                    "SELECT COUNT(*) FROM agents_fts WHERE agents_fts MATCH ?",
                )
                .bind(&fts_query)
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
                .bind(&fts_query)
                .bind(per_page as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await?;

                (total as u64, rows)
            }
        } else if let Some(ver) = version {
            let total: i64 =
                sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM agents WHERE version = ?")
                    .bind(ver)
                    .fetch_one(&self.pool)
                    .await
                    .map(|(n,)| n)
                    .unwrap_or(0);

            let rows = sqlx::query_as::<_, (String, String)>(
                    "SELECT hash, ad_json FROM agents WHERE version = ? ORDER BY inserted_at DESC LIMIT ? OFFSET ?",
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

    // ── Settings ─────────────────────────────────────────────────────────────

    pub async fn load_setting(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query_as::<_, (String,)>("SELECT value FROM settings WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(v,)| v))
    }

    pub async fn save_setting(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at)
             VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
             ON CONFLICT(key) DO UPDATE SET
                 value = excluded.value,
                 updated_at = excluded.updated_at",
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
                sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM credentials WHERE name LIKE ?")
                    .bind(&pattern)
                    .fetch_one(&self.pool)
                    .await
                    .map(|(n,)| n)
                    .unwrap_or(0);

            let rows = sqlx::query_as::<_, (i64, String, String, String, Option<String>, Option<String>, String, String, Option<String>)>(
                "SELECT id, name, kind, payload, schema_type, issuer_did, created_at, updated_at, expires_at
                 FROM credentials WHERE name LIKE ?
                 ORDER BY updated_at DESC LIMIT ? OFFSET ?",
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
                 ORDER BY updated_at DESC LIMIT ? OFFSET ?",
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
        let result = sqlx::query(
            "INSERT INTO credentials (name, kind, payload, schema_type, issuer_did, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&entry.name)
        .bind(&entry.kind)
        .bind(&entry.payload)
        .bind(&entry.schema_type)
        .bind(&entry.issuer_did)
        .bind(&entry.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn update_credential(&self, entry: &CredentialEntry) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE credentials SET
                 name = ?, kind = ?, payload = ?, schema_type = ?, issuer_did = ?, expires_at = ?
             WHERE id = ?",
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
        let result = sqlx::query("DELETE FROM credentials WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use pap_did::PrincipalKeypair;
    use pap_marketplace::AgentAdvertisement;
    use rand::rngs::OsRng;

    async fn in_memory_store() -> SqliteStore {
        let s = SqliteStore::connect("sqlite::memory:").await.unwrap();
        s.migrate().await.unwrap();
        s
    }

    fn make_signed_ad(name: &str) -> AgentAdvertisement {
        let key = SigningKey::generate(&mut OsRng);
        let kp = PrincipalKeypair::from_bytes(&key.to_bytes()).unwrap();
        let did = kp.did();
        let mut ad = AgentAdvertisement::new(
            name,
            "TestCorp",
            &did,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad.sign(&key).expect("Ed25519 is always supported");
        ad
    }

    // ── Migrations ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let s = in_memory_store().await;
        // Second call must not error (sqlx tracks applied versions)
        s.migrate().await.unwrap();
    }

    // ── Agents ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn agent_insert_and_load_all() {
        let s = in_memory_store().await;
        let ad = make_signed_ad("SearchBot");
        let hash = ad.hash();
        s.insert_agent(&hash, &ad).await.unwrap();
        let all = s.load_all_agents().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "SearchBot");
    }

    #[tokio::test]
    async fn agent_delete_returns_true_then_false() {
        let s = in_memory_store().await;
        let ad = make_signed_ad("DeleteBot");
        let hash = ad.hash();
        s.insert_agent(&hash, &ad).await.unwrap();
        assert!(s.delete_agent(&hash).await.unwrap());
        assert!(!s.delete_agent(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn agent_search_by_name() {
        let s = in_memory_store().await;
        let ad = make_signed_ad("FlightSearcher");
        let hash = ad.hash();
        s.insert_agent(&hash, &ad).await.unwrap();
        let page = s
            .search_agents(Some("FlightSearcher"), None, 1, 20)
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].ad.name, "FlightSearcher");
    }

    #[tokio::test]
    async fn agent_search_empty_query_returns_all() {
        let s = in_memory_store().await;
        s.insert_agent(&make_signed_ad("A").hash(), &make_signed_ad("A"))
            .await
            .unwrap();
        s.insert_agent(&make_signed_ad("B").hash(), &make_signed_ad("B"))
            .await
            .unwrap();
        let page = s.search_agents(None, None, 1, 20).await.unwrap();
        assert_eq!(page.total, 2);
    }

    #[tokio::test]
    async fn agent_search_special_chars_no_error() {
        // Regression test for I8: FTS5 special chars must not cause an error.
        let s = in_memory_store().await;
        let result = s.search_agents(Some("(NOT\"*"), None, 1, 20).await;
        assert!(
            result.is_ok(),
            "FTS special chars caused an error: {:?}",
            result.err()
        );
    }

    // ── Peers ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn peer_upsert_and_load_all() {
        let s = in_memory_store().await;
        let peer =
            pap_federation::peer::RegistryPeer::new("did:key:zPeer1", "https://peer1.example.com");
        s.upsert_peer(&peer).await.unwrap();
        let peers = s.load_all_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].did, "did:key:zPeer1");
    }

    #[tokio::test]
    async fn peer_delete_returns_true_then_false() {
        let s = in_memory_store().await;
        let peer =
            pap_federation::peer::RegistryPeer::new("did:key:zPeer2", "https://p2.example.com");
        s.upsert_peer(&peer).await.unwrap();
        assert!(s.delete_peer("did:key:zPeer2").await.unwrap());
        assert!(!s.delete_peer("did:key:zPeer2").await.unwrap());
    }

    #[tokio::test]
    async fn peer_upsert_updates_endpoint() {
        let s = in_memory_store().await;
        let peer1 =
            pap_federation::peer::RegistryPeer::new("did:key:zPeer3", "https://old.example.com");
        s.upsert_peer(&peer1).await.unwrap();
        let peer2 =
            pap_federation::peer::RegistryPeer::new("did:key:zPeer3", "https://new.example.com");
        s.upsert_peer(&peer2).await.unwrap();
        let peers = s.load_all_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].endpoint, "https://new.example.com");
    }

    #[tokio::test]
    async fn peer_sync_time_update() {
        let s = in_memory_store().await;
        let peer =
            pap_federation::peer::RegistryPeer::new("did:key:zPeer4", "https://p4.example.com");
        s.upsert_peer(&peer).await.unwrap();
        let ts = chrono::Utc::now();
        s.update_peer_sync_time("did:key:zPeer4", ts).await.unwrap();
        let peers = s.load_all_peers().await.unwrap();
        assert!(peers[0].last_sync.is_some());
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn identity_load_empty_returns_none() {
        let s = in_memory_store().await;
        assert!(s.load_identity().await.unwrap().is_none());
    }

    // ── Settings ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn setting_load_missing_returns_none() {
        let s = in_memory_store().await;
        assert!(s.load_setting("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn setting_save_and_load_roundtrip() {
        let s = in_memory_store().await;
        s.save_setting("cors_allowed_origins", "https://example.com")
            .await
            .unwrap();
        let v = s.load_setting("cors_allowed_origins").await.unwrap();
        assert_eq!(v.as_deref(), Some("https://example.com"));
    }

    #[tokio::test]
    async fn setting_save_updates_existing() {
        let s = in_memory_store().await;
        s.save_setting("cors_allowed_origins", "https://first.example.com")
            .await
            .unwrap();
        s.save_setting(
            "cors_allowed_origins",
            "https://first.example.com,https://second.example.com",
        )
        .await
        .unwrap();
        let v = s.load_setting("cors_allowed_origins").await.unwrap();
        assert_eq!(
            v.as_deref(),
            Some("https://first.example.com,https://second.example.com")
        );
    }

    #[tokio::test]
    async fn identity_save_and_load_roundtrip() {
        let s = in_memory_store().await;
        let identity = NodeIdentity {
            did: "did:key:zNode".into(),
            signing_key_bytes: [0xAB; 32],
        };
        s.save_identity(&identity).await.unwrap();
        let loaded = s.load_identity().await.unwrap().unwrap();
        assert_eq!(loaded.did, "did:key:zNode");
        assert_eq!(loaded.signing_key_bytes, [0xAB; 32]);
    }
}
