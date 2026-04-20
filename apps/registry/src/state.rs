use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

use pap_federation::registry::FederatedRegistry;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::db::RegistryStore;

// ── Sync event log ─────────────────────────────────────────────────────────

/// A single federation sync event recorded when a peer sync succeeds or fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEvent {
    /// RFC3339 timestamp.
    pub ts: String,
    /// `"success"` or `"error"`.
    pub outcome: String,
    /// Number of new agents merged (0 on error).
    pub merged_count: usize,
    /// Error message if outcome is `"error"`.
    pub error: Option<String>,
}

/// In-memory ring buffer of sync events per peer (last 100 per peer).
/// Not persisted across restarts — sufficient for operator diagnostics.
#[derive(Clone, Default)]
pub struct SyncEventLog {
    inner: Arc<Mutex<HashMap<String, VecDeque<SyncEvent>>>>,
}

impl SyncEventLog {
    /// Record a sync event for `peer_did`, keeping only the last 100.
    pub fn record(&self, peer_did: &str, event: SyncEvent) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let deque = map.entry(peer_did.to_owned()).or_default();
        deque.push_front(event);
        deque.truncate(100);
    }

    /// Return up to 100 most-recent events for `peer_did`, newest first.
    pub fn get(&self, peer_did: &str) -> Vec<SyncEvent> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(peer_did)
            .map(|d| d.iter().cloned().collect())
            .unwrap_or_default()
    }
}

// ── AppState ───────────────────────────────────────────────────────────────

/// The settings key used to persist the CORS origin allowlist.
pub const SETTING_CORS_ORIGINS: &str = "cors_allowed_origins";

/// Shared application state passed into all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Mutex<FederatedRegistry>>,
    pub store: Arc<RegistryStore>,
    pub node_did: String,
    pub node_endpoint: String,
    pub cert_fingerprint: String,
    pub admin_token: Option<String>,
    pub max_ads_per_principal: usize,
    /// In-memory per-peer sync event log.
    pub sync_log: SyncEventLog,
    /// Live CORS origin allowlist — persisted in the `settings` table and
    /// updated at runtime without restarting the server.
    /// Each entry is an exact origin string, e.g. `"https://app.example.com"`.
    /// An empty list means allow nothing (safe default until seeded).
    pub cors_allowed_origins: Arc<RwLock<Vec<String>>>,
}

impl AppState {
    pub fn new(
        registry: Arc<Mutex<FederatedRegistry>>,
        store: Arc<RegistryStore>,
        node_did: String,
        config: &Config,
        cert_fingerprint: String,
        cors_allowed_origins: Arc<RwLock<Vec<String>>>,
    ) -> Self {
        Self {
            registry,
            store,
            node_did,
            node_endpoint: config.public_endpoint.clone(),
            cert_fingerprint,
            admin_token: config.admin_token.clone(),
            max_ads_per_principal: config.max_ads_per_principal,
            sync_log: SyncEventLog::default(),
            cors_allowed_origins,
        }
    }

    /// Check whether the given Bearer token is authorized for admin access.
    /// If no admin token is configured, all requests are allowed.
    /// Uses constant-time comparison to prevent timing-based token oracle attacks.
    pub fn is_authorized(&self, token: Option<&str>) -> bool {
        match &self.admin_token {
            None => true,
            Some(expected) => token
                .map(|t| constant_time_eq::constant_time_eq(t.as_bytes(), expected.as_bytes()))
                .unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{sqlite::SqliteStore, RegistryStore};

    async fn make_state(token: Option<&str>) -> AppState {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("src/db/migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        AppState {
            registry: Arc::new(Mutex::new(FederatedRegistry::new())),
            store: Arc::new(RegistryStore::Sqlite(SqliteStore { pool })),
            node_did: "did:key:zTest".into(),
            node_endpoint: "http://localhost".into(),
            cert_fingerprint: "sha256:test".into(),
            admin_token: token.map(str::to_owned),
            max_ads_per_principal: 100,
            sync_log: SyncEventLog::default(),
            cors_allowed_origins: Arc::new(RwLock::new(vec![])),
        }
    }

    #[tokio::test]
    async fn is_authorized_no_token_configured_accepts_no_cred() {
        let state = make_state(None).await;
        assert!(state.is_authorized(None));
    }

    #[tokio::test]
    async fn is_authorized_no_token_configured_accepts_any_cred() {
        let state = make_state(None).await;
        assert!(state.is_authorized(Some("anything")));
    }

    #[tokio::test]
    async fn is_authorized_correct_token() {
        let state = make_state(Some("secret")).await;
        assert!(state.is_authorized(Some("secret")));
    }

    #[tokio::test]
    async fn is_authorized_wrong_token_rejected() {
        let state = make_state(Some("secret")).await;
        assert!(!state.is_authorized(Some("wrong")));
    }

    #[tokio::test]
    async fn is_authorized_missing_bearer_rejected() {
        let state = make_state(Some("secret")).await;
        assert!(!state.is_authorized(None));
    }
}
