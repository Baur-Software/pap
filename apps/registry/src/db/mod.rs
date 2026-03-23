pub mod config;
pub(crate) mod postgres;
pub(crate) mod sqlite;

pub use config::DbConfig;
use postgres::PostgresStore;
use sqlite::SqliteStore;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use pap_federation::peer::RegistryPeer;
use pap_marketplace::AgentAdvertisement;

// ── Shared data types ────────────────────────────────────────────────────────

pub struct NodeIdentity {
    pub did: String,
    pub signing_key_bytes: [u8; 32],
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentEntry {
    pub hash: String,
    pub ad: AgentAdvertisement,
}

pub struct AgentsPage {
    pub items: Vec<AgentEntry>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

// ── Enum-dispatch store ──────────────────────────────────────────────────────

pub enum RegistryStore {
    Sqlite(SqliteStore),
    Postgres(PostgresStore),
}

impl RegistryStore {
    pub async fn connect(cfg: &DbConfig) -> Result<Self> {
        match cfg {
            DbConfig::Sqlite { .. } => {
                let s = SqliteStore::connect(&cfg.connection_string()).await?;
                Ok(RegistryStore::Sqlite(s))
            }
            DbConfig::Postgres { .. } => {
                let p = PostgresStore::connect(&cfg.connection_string()).await?;
                Ok(RegistryStore::Postgres(p))
            }
        }
    }

    pub async fn migrate(&self) -> Result<()> {
        match self {
            RegistryStore::Sqlite(s) => s.migrate().await,
            RegistryStore::Postgres(p) => p.migrate().await,
        }
    }

    // ── Node identity ────────────────────────────────────────────────────────

    pub async fn load_identity(&self) -> Result<Option<NodeIdentity>> {
        match self {
            RegistryStore::Sqlite(s) => s.load_identity().await,
            RegistryStore::Postgres(p) => p.load_identity().await,
        }
    }

    pub async fn save_identity(&self, identity: &NodeIdentity) -> Result<()> {
        match self {
            RegistryStore::Sqlite(s) => s.save_identity(identity).await,
            RegistryStore::Postgres(p) => p.save_identity(identity).await,
        }
    }

    // ── Agents ───────────────────────────────────────────────────────────────

    pub async fn load_all_agents(&self) -> Result<Vec<AgentAdvertisement>> {
        match self {
            RegistryStore::Sqlite(s) => s.load_all_agents().await,
            RegistryStore::Postgres(p) => p.load_all_agents().await,
        }
    }

    pub async fn insert_agent(&self, hash: &str, ad: &AgentAdvertisement) -> Result<()> {
        match self {
            RegistryStore::Sqlite(s) => s.insert_agent(hash, ad).await,
            RegistryStore::Postgres(p) => p.insert_agent(hash, ad).await,
        }
    }

    pub async fn delete_agent(&self, hash: &str) -> Result<bool> {
        match self {
            RegistryStore::Sqlite(s) => s.delete_agent(hash).await,
            RegistryStore::Postgres(p) => p.delete_agent(hash).await,
        }
    }

    pub async fn search_agents(
        &self,
        q: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> Result<AgentsPage> {
        match self {
            RegistryStore::Sqlite(s) => s.search_agents(q, page, per_page).await,
            RegistryStore::Postgres(p) => p.search_agents(q, page, per_page).await,
        }
    }

    // ── Peers ────────────────────────────────────────────────────────────────

    pub async fn load_all_peers(&self) -> Result<Vec<RegistryPeer>> {
        match self {
            RegistryStore::Sqlite(s) => s.load_all_peers().await,
            RegistryStore::Postgres(p) => p.load_all_peers().await,
        }
    }

    pub async fn upsert_peer(&self, peer: &RegistryPeer) -> Result<()> {
        match self {
            RegistryStore::Sqlite(s) => s.upsert_peer(peer).await,
            RegistryStore::Postgres(p) => p.upsert_peer(peer).await,
        }
    }

    pub async fn delete_peer(&self, did: &str) -> Result<bool> {
        match self {
            RegistryStore::Sqlite(s) => s.delete_peer(did).await,
            RegistryStore::Postgres(p) => p.delete_peer(did).await,
        }
    }

    pub async fn update_peer_sync_time(&self, did: &str, ts: DateTime<Utc>) -> Result<()> {
        match self {
            RegistryStore::Sqlite(s) => s.update_peer_sync_time(did, ts).await,
            RegistryStore::Postgres(p) => p.update_peer_sync_time(did, ts).await,
        }
    }
}
