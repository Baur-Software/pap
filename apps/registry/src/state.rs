use std::sync::{Arc, Mutex};

use pap_federation::registry::FederatedRegistry;

use crate::config::Config;
use crate::db::RegistryStore;

/// Shared application state passed into all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Mutex<FederatedRegistry>>,
    pub store: Arc<RegistryStore>,
    pub node_did: String,
    pub node_endpoint: String,
    pub cert_fingerprint: String,
    pub admin_token: Option<String>,
}

impl AppState {
    pub fn new(
        registry: Arc<Mutex<FederatedRegistry>>,
        store: Arc<RegistryStore>,
        node_did: String,
        config: &Config,
        cert_fingerprint: String,
    ) -> Self {
        Self {
            registry,
            store,
            node_did,
            node_endpoint: config.public_endpoint.clone(),
            cert_fingerprint,
            admin_token: config.admin_token.clone(),
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
